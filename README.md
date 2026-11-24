# LLMSCAN

This version extends [PurCL/LLMSCAN](https://github.com/PurCL/LLMSCAN) with
Source-to-Traffic analysis. The original project's MIT license and attribution
are retained. Third-party source trees, downloaded dependencies, local credentials
and generated reports are excluded from this repository.

LLMSCAN is a tool designed to parse and analyze source code to instantiate LLM-based program analysis. Based on Tree-sitter, it provides functionality to identify and extract functions from the source code, along with their metadata such as function name, line numbers, parameters, call sites, and other program constructs (including branches and loops). Importantly, it achieves light-weighted call graph analysis based on parsing, which enables more effective code browsing and navigation for real-world programs. The latest version of LLMSCAN can support five programming languages, including C, C++, Java, Python, and Go.

**Attention**: Considering the language syntax differences, we give up supporting multiple languages in main branch. Since 2025/03/01, the active development branches have been cpp, java, python, and go.


## Features

- Parse source code using Tree-sitter.
- Browse code for prompting-based static analysis.
- Multi-linguistic support.

## Functionality

- MetaScan: Extract syntactic facts as function metadata.

- TrafficScan (Source-to-Traffic analysis): recover how a network program builds the bytes it sends
  (encapsulation, encryption, record/frame construction, fragmentation, buffering) from its source and
  pinned dependencies, and derive candidate externally observable traffic features (record/payload
  lengths, sequences, ranges) with source evidence, trigger conditions and confidence labels.
  Currently implemented for Go (dependencies and the matching Go standard library are fetched
  automatically). See `docs/TRAFFICSCAN.md`; run `cd src && ./run_trafficscan.sh`.

You can define your own scanners in the directory `src/pipeline`.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/Sherrylacer/trafficscan.git
    cd trafficscan
    ```

2. Install the required dependencies:
    ```sh
    python3.11 -m venv .venv
    source .venv/bin/activate
    python -m pip install -r requirements.txt
    ```

3. Ensure you have the Tree-sitter library and language bindings installed:
    ```sh
    python lib/build.py
    ```

4. Configure the keys if LLM annotations are needed (static TrafficScan does not require an API key):
    ```sh
    export OPENAI_API_KEY="YOUR_API_KEY"
    export OPENAI_BASE_URL="https://api.openai.com/v1"
    ```
    Alternatively, copy `src/model/local_config.example.json` to
    `src/model/local_config.json` and fill in your settings. The local configuration
    is ignored by Git; environment variables override it.

    Similarly, the other two keys can be set as follows:
    ```sh
    export REPLICATE_API_TOKEN="YOUR_REPLICATE_TOKEN"
    export GEMINI_KEY="YOUR_GEMINI_KEY"
    ```

## Quick Start

For Source-to-Traffic analysis of an existing Go project:

```sh
source .venv/bin/activate
cd src
python scan.py --language Go --project-path /path/to/go-project --scanners trafficscan
```

Go standard library and module sources are downloaded into `cache/` on first use.
Pass `--go-version` to select the standard library version, and `--use-llm` for
optional interpretations. See [docs/TRAFFICSCAN.md](docs/TRAFFICSCAN.md).
Xray source code must be obtained separately; it is not bundled here.

1. Prepare the project that you want to analyze. Here we use the Linux kernel as an example:
    ```sh
    cd benchmark
    mkdir C && cd C
    git clone git@github.com:torvalds/linux.git
    ```

    Benchmark source trees must be obtained separately. Small test fixtures are
    included under `tests/fixtures/`.

2. Run the analysis to extract the meta data of each function:
    ```sh
    cd src
    ./run.sh
    ```

The output files are dumped in the directory `log`.

## How to Extend

### More Program Facts

You can implement your own analysis by adding more modules, such as more parsing-based primitives (in `parser/program_parser`). If you want to derive semantic facts, which may be beyond the capability of parsing-based analysis, you can customize the prompts and leverage LLMs to derive them in a neural manner.

### More Programming Languages

The framework is language-agnostic. To migrate the current implementations to other programming languages or extract more syntactic facts, please refer to the grammar files in the corresponding Tree-sitter libraries and refactor the code in `parser/program_parser.py`. Basically, you only need to change the node types when invoking `find_nodes_by_type`.

Here are the links to grammar files in Tree-sitter libraries targeting mainstream programming languages:

- C: https://github.com/tree-sitter/tree-sitter-c/blob/master/src/grammar.json
- C++: https://github.com/tree-sitter/tree-sitter-cpp/blob/master/src/grammar.json
- Java: https://github.com/tree-sitter/tree-sitter-java/blob/master/src/grammar.json
- Python: https://github.com/tree-sitter/tree-sitter-python/blob/master/src/grammar.json
- Go: https://github.com/tree-sitter/tree-sitter-go/blob/master/src/grammar.json
- JavaScript: https://github.com/tree-sitter/tree-sitter-javascript/blob/master/src/grammar.json

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under [MIT license](LICENSE).

## Contact

For any questions or suggestions, please contact [stephenw.wangcp@gmail.com](mailto:stephenw.wangcp@gmail.com).
