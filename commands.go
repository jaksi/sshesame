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
		fmt.Fprintf(context.stdout, "%v: command not found\n", context.args[0])
		return 127, nil
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
	for err == nil {
		fmt.Fprint(context.stdout, prompt)
		line, err = context.stdin.ReadLine()
		args := strings.Fields(line)
		if len(args) > 0 && args[0] == "exit" {
			var err error
			var status int
			if len(args) > 1 {
				status, err = strconv.Atoi(args[1])
				if err != nil {
					status = 255
				}
			}
			return uint32(status), nil
		}
		if err == nil {
			newContext := context
			newContext.args = strings.Fields(line)
			_, err = executeProgram(newContext)
		}
	}
	return 0, err
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
	var line string
	var err error
	for err == nil {
		line, err = context.stdin.ReadLine()
		fmt.Fprintln(context.stdout, line)
	}
	return 0, err
}
