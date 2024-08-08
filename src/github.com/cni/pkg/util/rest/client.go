package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/emicklei/go-restful/v3"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

type Client struct {
	Client  *http.Client
	BaseURL string
}

func NewClient(client *http.Client, baseURL string) *Client {
	return &Client{Client: client, BaseURL: baseURL}
}

type BaseClient interface {
	Do(req *http.Request) (*http.Response, error)
	Request(method string, path string, body interface{}, respObj interface{}) (int, error)
	PrepareRequest(method string, path string, body interface{}) (*http.Request, error)
	CheckResponse(method string, path string, body interface{}, resp *http.Response) (*http.Response, error)
}

func Request(c BaseClient, method string, path string, body interface{}, respObj interface{}) (code int, err error) {
	code = http.StatusInternalServerError
	req, err := c.PrepareRequest(method, path, body)
	if err != nil {
		return
	}
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	resp, err = c.CheckResponse(method, path, body, resp)
	if err != nil {
		if resp != nil {
			code = resp.StatusCode
		}
		return
	}
	defer resp.Body.Close()
	if respObj != nil {
		var respBody []byte
		respBody, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return
		}
		if err = json.Unmarshal(respBody, respObj); err != nil {
			err = NewJsonDecodingError(respBody, respObj, err)
			return
		}
	}
	return resp.StatusCode, nil
}
func (c *Client) Request(method string, path string, body interface{}, respObj interface{}) (int, error) {
	return Request(c, method, path, body, respObj)
}
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Content-Type", restful.MIME_JSON)
	req.Header.Set("Accept", restful.MIME_JSON)
	resp, err := c.Client.Do(req)
	if err != nil {
		return resp, err
	}
	return resp, nil
}
func (c *Client) PrepareRequest(method string, path string, body interface{}) (*http.Request, error) {
	absPath := URLJoin(c.BaseURL, path)
	var reqBody io.Reader
	if body == nil {
		reqBody = nil
	} else {
		jsonStr, err := json.Marshal(body)
		if err != nil {
			return nil, NewJsonEncodingError(body, err)
		}
		reqBody = bytes.NewReader(jsonStr)
	}
	req, err := http.NewRequest(method, absPath, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create new http request ;method %s,path %s,body %v,error is %v", method, absPath, body, err)
	}
	return req, nil
}
func (c *Client) CheckResponse(method string, path string, body interface{}, resp *http.Response) (*http.Response, error) {
	if IsBadResponse(resp) {
		var errorResp ErrorResp
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return resp, err
		}
		if method == http.MethodDelete {
			return resp, NewBadResponseError(method, path, body, http.StatusText(resp.StatusCode))
		}
		if err := json.Unmarshal(respBody, &errorResp); err != nil {
			return resp, NewJsonDecodingError(respBody, errorResp, err)
		}
		return resp, NewBadResponseError(method, path, body, errorResp.Error.Message)
	}
	return resp, nil
}
func IsBadResponse(resp *http.Response) bool {
	return resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices
}
func URLJoin(base, url string) string {
	if base == "" {
		return url
	}
	if url == "" {
		return base
	}
	slash := "/"
	if strings.HasSuffix(base, slash) {
		base = strings.TrimSuffix(base, slash)
	}
	if strings.HasPrefix(url, slash) {
		url = strings.TrimSuffix(url, slash)
	}
	return fmt.Sprintf("%s%s", base, url)
}
