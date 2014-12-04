package http

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
)

type Client interface {
	Do(*http.Request) (*http.Response, error)
}

type HandlerClient struct {
	Handler http.Handler
}

func (hc *HandlerClient) Do(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	hc.Handler.ServeHTTP(w, r)

	resp := http.Response{
		StatusCode: w.Code,
		Header:     w.Header(),
		Body:       ioutil.NopCloser(w.Body),
	}

	return &resp, nil
}

type RequestRecorder struct {
	Request *http.Request
}

func (r *RequestRecorder) Do(req *http.Request) (*http.Response, error) {
	r.Request = req
	return nil, errors.New("error")
}
