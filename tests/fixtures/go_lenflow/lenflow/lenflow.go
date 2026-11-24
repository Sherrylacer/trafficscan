package lenflow

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func twice(record, payload []byte, k int) []byte {
	var x []byte
	if k > 0 {
		record, x = sliceForAppend(record, k)
	}
	record, x = sliceForAppend(record, len(payload)+3)
	_ = x
	return record
}
