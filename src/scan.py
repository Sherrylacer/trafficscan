import os
import argparse
import glob
from model.utils import *
from pipeline.metascan import *
from pipeline.trafficscan import TrafficScanPipeline

class BatchScan:
    def __init__(
        self,
        project_path: str,
        language: str,
        inference_model_name: str,
        inference_key_str: str,
        temperature: float,
        scanners: list,
        traffic_options: dict = None
    ):
        """
        Initialize BatchScan object with project details.
        """
        self.project_path = project_path
        self.language = language
        self.scanners = scanners

        self.all_files = {}
        self.inference_model_name = inference_model_name
        self.inference_key_str = inference_key_str
        self.temperature = temperature
        self.batch_scan_statistics = {}
        self.traffic_options = traffic_options or {}

        suffixs = []
        if self.language == "C":
            suffixs = ["c", "h"]
        elif self.language == "C++":
            suffixs = ["cpp", "cc", "hpp", "c", "h"]
        elif self.language == "Java":
            suffixs = ["java"]
        elif self.language == "Python":
            suffixs = ["py"]
        elif self.language == "Go":
            suffixs = ["go"]

        # Load all files with the specified suffix in the project path
        # (trafficscan loads packages itself, with build constraints and dependencies)
        if any(s != "trafficscan" for s in self.scanners):
            self.travese_files(project_path, suffixs)

        print(len(self.all_files))

    def start_batch_scan(self) -> None:
        """
        Start the batch scan process.
        """
        parts = self.project_path.rstrip("/").split("/")
        project_name = parts[-2] + "_" + parts[-1] if len(parts) >= 2 else parts[-1]

        if "metascan" in self.scanners:
            metascan_pipeline = MetaScanPipeline(
                project_name,
                self.language,
                self.all_files,
                self.inference_model_name,
                self.inference_key_str,
                self.temperature
            )
            metascan_pipeline.start_scan()

        if "trafficscan" in self.scanners:
            pipeline = TrafficScanPipeline(
                project_name,
                self.project_path,
                self.language,
                self.inference_model_name,
                self.inference_key_str,
                self.temperature,
                self.traffic_options,
            )
            pipeline.start_scan()

    def travese_files(self, project_path: str, suffixs: List) -> None:
        """
        Traverse all files in the project path.
        """
        for suffix in suffixs:
            for file in glob.glob(f"{project_path}/**/*.{suffix}", recursive=True):
                with open(file, "r") as c_file:
                    c_file_content = c_file.read()
                    self.all_files[file] = c_file_content


def run_dev_mode():
    """
    Run in development mode by parsing arguments and starting the batch scan.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--project-path",
        type=str,
        help="Specify the project path",
    )
    parser.add_argument(
        "--language",
        choices=[
            "C",
            "C++",
            "Java",
            "Python",
            "Go"
        ],
        help="Specify the language",
    )
    parser.add_argument(
        "--inference-model",
        type=str,
        default="gpt-6-sol",  # 默认使用 GPT-6 Sol，需 API 服务支持该模型 ID
        help="Specify LLM model for Inference (default: gpt-6-sol; e.g., gpt-4o, gemini)",
    )
    parser.add_argument(
        "--global-temperature",
        choices=["0.0", "0.5", "0.7", "1.0", "1.5", "1.7", "2.0"],
        default="0.0",
        help="Specify the temperature",
    )
    parser.add_argument(
        "--scanners",
        nargs='+',
        choices=["metascan", "trafficscan"],
        help="Specify which scanners to invoke",
    )
    # ---- trafficscan (Source-to-Traffic analysis) options
    parser.add_argument("--go-version", type=str, default=None,
                        help="Go toolchain version whose standard library is analysed (e.g. 1.27.3); "
                             "default: from go.mod toolchain/go directive")
    parser.add_argument("--goos", type=str, default="linux", help="GOOS for build constraints (default linux)")
    parser.add_argument("--goarch", type=str, default="amd64", help="GOARCH for build constraints (default amd64)")
    parser.add_argument("--build-tags", nargs="*", default=None, help="extra Go build tags")
    parser.add_argument("--cache-dir", type=str, default=None, help="dependency cache (default <repo>/cache)")
    parser.add_argument("--offline", action="store_true", help="do not download dependencies")
    parser.add_argument("--package-filter", nargs="*", default=None,
                        help="only scan packages whose import path contains one of these substrings")
    parser.add_argument("--entry-timeout", type=int, default=60, help="seconds per entry point")
    parser.add_argument("--use-llm", action="store_true",
                        help="annotate top features with the LLM (labelled unverified; never changes values)")
    parser.add_argument("--llm-features", type=int, default=8, help="number of features to annotate")
    parser.add_argument("--top-n", type=int, default=30, help="features detailed in the Markdown report")

    args = parser.parse_args()
    project_path = args.project_path
    language = args.language
    inference_model = args.inference_model
    global_temperature = float(args.global_temperature)
    scanners = args.scanners if args.scanners else []
    inference_model_key = standard_keys[0]
    traffic_options = {
        "go_version": args.go_version,
        "goos": args.goos,
        "goarch": args.goarch,
        "build_tags": args.build_tags,
        "cache_dir": args.cache_dir,
        "offline": args.offline,
        "package_filter": args.package_filter,
        "entry_timeout": args.entry_timeout,
        "use_llm": args.use_llm,
        "llm_features": args.llm_features,
        "top_n": args.top_n,
    }

    batch_scan = BatchScan(
        project_path,
        language,
        inference_model,
        inference_model_key,
        global_temperature,
        scanners,
        traffic_options
    )
    print("Starting batch scan...")
    batch_scan.start_batch_scan()


if __name__ == "__main__":
    run_dev_mode()
