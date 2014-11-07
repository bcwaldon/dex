package provider

import (
	"encoding/json"
	"io"
	"io/ioutil"
)

type Client struct {
	ID     string
	Secret string
}

type ClientRepo interface {
	Client(id string) *Client
}

func NewClientRepoFromReader(r io.Reader) (ClientRepo, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var cs []Client
	if err = json.Unmarshal(b, &cs); err != nil {
		return nil, err
	}

	cr := memClientRepo{
		clients: make(map[string]Client, len(cs)),
	}

	for _, c := range cs {
		c := c
		cr.clients[c.ID] = c
	}

	return &cr, nil
}

type memClientRepo struct {
	clients map[string]Client
}

func (cr *memClientRepo) Client(id string) *Client {
	ci, ok := cr.clients[id]
	if !ok {
		return nil
	}
	return &ci
}
