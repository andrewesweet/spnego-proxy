package main

import "sync/atomic"

// stubTokenProvider is a controllable TokenProvider for testing.
// It lives in a dedicated file so the cross-file dependency between
// test files that use it is explicit and discoverable.
type stubTokenProvider struct {
	calls  atomic.Int64
	err    error  // when non-nil, GetToken returns this error
	token  string // returned on success
	closed atomic.Bool
}

func (s *stubTokenProvider) GetToken() (string, error) {
	s.calls.Add(1)
	if s.err != nil {
		return "", s.err
	}
	return s.token, nil
}

func (s *stubTokenProvider) Close() error {
	s.closed.Store(true)
	return nil
}
