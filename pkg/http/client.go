package http

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
)

type Client interface {
	Do(*http.Request) (*http.Response, error)
}

type HandlerClient struct {
	hdlr http.Handler
}

func (hc *HandlerClient) Do(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	hc.hdlr.ServeHTTP(w, r)

	resp := http.Response{
		StatusCode: w.Code,
		Header:     w.Header(),
		Body:       ioutil.NopCloser(w.Body),
	}

	return &resp, nil
}
