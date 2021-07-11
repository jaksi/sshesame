package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

type readLiner interface {
	ReadLine() (string, error)
}

type commandContext struct {
	args           []string
	stdin          readLiner
	stdout, stderr io.Writer
	pty            bool
}

type command interface {
	execute(context commandContext) (uint32, error)
}

var commands = map[string]command{
	"sh":    cmdShell{},
	"true":  cmdTrue{},
	"false": cmdFalse{},
	"echo":  cmdEcho{},
	"cat":   cmdCat{},
}

var shellProgram = []string{"sh"}

func executeProgram(context commandContext) (uint32, error) {
	if len(context.args) == 0 {
		return 0, nil
	}
	command := commands[context.args[0]]
	if command == nil {
		_, err := fmt.Fprintf(context.stderr, "%v: command not found\n", context.args[0])
		return 127, err
	}
	return command.execute(context)
}

type cmdShell struct{}

func (cmdShell) execute(context commandContext) (uint32, error) {
	var prompt string
	if context.pty {
		prompt = "$ "
	}
	var line string
	var err error
	for {
		_, err = fmt.Fprint(context.stdout, prompt)
		if err != nil {
			return 0, err
		}
		line, err = context.stdin.ReadLine()
		if err != nil {
			return 0, err
		}
		args := strings.Fields(line)
		if len(args) > 0 && args[0] == "exit" {
			var err error
			var status uint64
			if len(args) > 1 {
				status, err = strconv.ParseUint(args[1], 10, 32)
				if err != nil {
					status = 255
				}
			}
			return uint32(status), nil
		}
		newContext := context
		newContext.args = strings.Fields(line)
		if _, err = executeProgram(newContext); err != nil {
			return 0, err
		}
	}
}

type cmdTrue struct{}

func (cmdTrue) execute(context commandContext) (uint32, error) {
	return 0, nil
}

type cmdFalse struct{}

func (cmdFalse) execute(context commandContext) (uint32, error) {
	return 1, nil
}

type cmdEcho struct{}

func (cmdEcho) execute(context commandContext) (uint32, error) {
	_, err := fmt.Fprintln(context.stdout, strings.Join(context.args[1:], " "))
	return 0, err
}

type cmdCat struct{}

func (cmdCat) execute(context commandContext) (uint32, error) {
	if len(context.args) > 1 {
		for _, file := range context.args[1:] {
			if _, err := fmt.Fprintf(context.stderr, "%v: %v: No such file or directory\n", context.args[0], file); err != nil {
				return 0, err
			}
		}
		return 1, nil
	}
	var line string
	var err error
	for err == nil {
		line, err = context.stdin.ReadLine()
		if err == nil {
			_, err = fmt.Fprintln(context.stdout, line)
		}
	}
	return 0, err
}
