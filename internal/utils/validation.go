package utils

import (
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
)

func GetErrorsFromRequestValidation(err error) (map[string]string, bool) {
	errs := make(map[string]string)
	var validationErrs validator.ValidationErrors
	if errors.As(err, &validationErrs) {
		for _, e := range validationErrs {
			err := e.ActualTag()
			if e.Param() != "" {
				err = fmt.Sprintf("%s=%s", err, e.Param())
			}
			errs[e.Field()] = err
		}
		return errs, true
	}
	return nil, false
}
