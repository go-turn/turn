package server

// SetBenchObserver lets the external benchmark switch (otel_bench_test.go)
// give the benchmark servers an Observer.
func SetBenchObserver(o Observer) { benchObserver = o }
