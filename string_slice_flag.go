package main

import (
	"strings"
)

type StringSliceFlag []string

func (s *StringSliceFlag) String() string {
	return strings.Join(*s, ";")
}

func (s *StringSliceFlag) Set(value string) (err error) {
	*s = append(*s, value)
	return err
}
