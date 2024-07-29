package rest

import (
	"fmt"
	"github.com/emicklei/go-restful/v3"
	"k8s.io/klog"
)

type JsonDecodingError struct {
	Data []byte
	V    interface{}
	Err  error
}

func (j JsonDecodingError) Error() string {
	return fmt.Sprintf("failed to perform json deserializaition on %s to %v : %v", j.Data, j.V, j.Err)
}
func NewJsonDecodingError(data []byte, v interface{}, err error) JsonDecodingError {
	return JsonDecodingError{
		Data: data,
		V:    v,
		Err:  err,
	}
}

type JsonEncodingError struct {
	V   interface{}
	Err error
}

func (j JsonEncodingError) Error() string {
	return fmt.Sprintf("failed to perform json deserializaition on %v : %v", j.V, j.Err)
}
func NewJsonEncodingError(v interface{}, err error) JsonEncodingError {
	return JsonEncodingError{
		V:   v,
		Err: err,
	}
}

type BadResponseError struct {
	Method       string
	Path         string
	Body         interface{}
	ErrorMessage string
}

func (bs BadResponseError) Error() string {
	return fmt.Sprintf("Bad Response from request method %s url %s body %v : %s", bs.Method, bs.Path, bs.Body, bs.ErrorMessage)
}
func NewBadResponseError(method string, path string, body interface{}, message string) BadResponseError {
	return BadResponseError{
		Method:       method,
		Path:         path,
		Body:         body,
		ErrorMessage: message,
	}
}

type ErrorResp struct {
	Error ErrorRespBody `json:"error"`
}
type ErrorRespBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func WriteError(resp *restful.Response, statusCode int, ErrCode, message string) {
	errorRespBody := ErrorRespBody{
		Code:    ErrCode,
		Message: message,
	}
	if err := resp.WriteHeaderAndJson(statusCode, errorRespBody, restful.MIME_JSON); err != nil {
		klog.Error(err)
	}
}
