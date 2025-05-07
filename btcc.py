#!/usr/bin/env python3

"""
BTCC

A compile to extend original bpftrace script.

New features:
    1. add define support:
        * example: 
            %define HELLO 0x1000
            %define MESSAGE "hello, world"

    2. add function macro support:
        * define function macro:
            %macro NAME($a, $b, ...)
            // macro body
            %end

        * call function macro with name and parameters:
            %call NAME($a, $b, ...)

    3. how to return a value from function macro?
        * set return value to the variable which name
            should be the same as function name.

        if the function name is "foo", set return value
        to "$foo": $foo = 10;

"""

import re
import sys

import argparse

RE_PARAM = re.compile(r"^\$[_a-zA-Z][_a-zA-Z0-9]*$")
RE_SUB_PARAM = re.compile(r"\$(?P<var>[_a-zA-Z][_a-zA-Z0-9]*)")

def warning(s):
    sys.stderr.write("Warning: %s\n" % s)

def die(s):
    sys.stderr.write("Error: %s\n" % s)
    sys.exit(1)

class CommandLineParser(object):
    DEFAULT_OUTPUT_FILE = "out.bt"

    def __init__(self):
        p = argparse.ArgumentParser(description="bpftrace extension compiler")
        p.add_argument("-o", "--out", 
                       default=self.DEFAULT_OUTPUT_FILE, 
                       help="output file(default: %s)" % self.DEFAULT_OUTPUT_FILE)
        p.add_argument("-f", "--file", help="source extended bt script to compile")
        self.parser = p

    def run(self):
        opts = self.parser.parse_args()
        if opts.file is None:
            die("script file is required")
        return opts

class Macro(object):
    def __init__(self, name, params):
        self.name = name
        self.params = params
        self.lines = list()
        self.expand_id = 0

    def add(self, line):
        self.lines.append(line)

    def _prefix(self):
        return "__m%d_" % self.expand_id

    def expand(self, args, call_line, lineno):
        ctx = list()
        if len(self.params) != len(args):
            die("macro expand arguments mismatched at line: %d" % lineno)

        var_prefix = self._prefix()

        # pass arguments
        ctx.append("\n// BEGIN: %s\n" % call_line)
        for (x, y) in zip(self.params, args):
            ctx.append("\t%s%s%s = %s;\n" % (x[0], var_prefix, x[1:], y))

        # expand body
        for line in self.lines:
            #expanded_line = RE_SUB_PARAM.sub("$%s\\g<var>" % var_prefix, line)
            expanded_line = self._expand_line(line, var_prefix)
            ctx.append(expanded_line)

        ctx.append("// END: %s\n" % call_line)
        self.expand_id += 1

        return "".join(ctx)

    def _expand_line(self, line, var_prefix):
        l = list()
        start = 0
        for m in RE_SUB_PARAM.finditer(line):
            var = m.group(1)
            if var != self.name:
                l.append(line[start:m.start()])
                l.append("$%s%s" % (var_prefix, var))
                start = m.end()

        if start < len(line):
            l.append(line[start:])

        return "".join(l)

class App(object):
    RE_MACRO_START = re.compile(r"^%macro\s+([_a-zA-Z][_a-zA-Z0-9]*)\s*\(([\s\$_A-Za-z0-9,]*)\)$")
    RE_MACRO_END = re.compile(r"^%end$")
    RE_MACRO_CALL = re.compile(r"^%call\s+([_a-zA-Z][_a-zA-Z0-9]*)\s*\(([\s\$_a-zA-Z0-9,]*)\)\s*;?$")
    RE_MACRO_DEFINE = re.compile(r"^%define\s+([_a-zA-Z][_A-Za-z0-9]*)\s+(\w+)\s*$")

    def __init__(self):
        self.opts = CommandLineParser().run()

    def parse_params(self, sparams, lineno):
        global RE_PARAM
        params = list()
        names = dict()

        s = sparams.strip()
        if len(s) == 0:
            return params
        args = map(lambda v: v.strip(), s.split(","))
        for arg in args:
            m = RE_PARAM.match(arg)
            if m:
                if arg in names:
                    die("duplicated parameter name (%s) at line: %d" % (arg, lineno))
                params.append(arg)
            else:
                die("invalid parameter name (%s) at line: %d" % (arg, lineno))

        return params

    def expand_defines(self, line, defines):
        s = line
        for k, v in defines.items():
            s = s.replace(k, v)
        return s
            
    def compile_script(self, input, output):
        macros = dict()
        defines = dict()
        context = list()
        current_macro = None
        with open(input) as fp:
            for lineno, line in enumerate(fp.readlines(), 1):
                s = line.strip()
                m = self.RE_MACRO_START.match(s)
                if m:
                    name, sp = m.group(1), m.group(2)
                    if current_macro is not None:
                        die("define nested macro (%s) in macro (%s) at line: %d" % (name, current_macro.name, lineno))

                    params = self.parse_params(sp, lineno)
                    current_macro = Macro(name, params)
                    continue

                m = self.RE_MACRO_END.match(s)
                if m:
                    if current_macro is None:
                        die("macro end is mismatched macro start at line: %d" % lineno)

                    name = current_macro.name
                    if name in macros:
                        die("found duplicated macro (%s) at line: %d" % (name, lineno))

                    macros[name] = current_macro
                    current_macro = None
                    continue

                m = self.RE_MACRO_CALL.match(s)
                if m:
                    name, sp = m.group(1), m.group(2)
                    args = self.parse_params(sp, lineno)
                    if current_macro is not None:
                        die("it is forbidden to use macro call in macro definition at line: %d" % lineno)

                    expand_macro = macros.get(name, None)
                    if expand_macro is None:
                        die("call an unknown macro (%s) at line: %d" % (name, lineno))

                    context.append(expand_macro.expand(args, s, lineno))
                    continue

                m = self.RE_MACRO_DEFINE.match(s)
                if m:
                    name, value = m.group(1), m.group(2)
                    if name in defines:
                        warning("redefine item (%s) will be overwritten at line: %d" % (name, lineno))
                    defines[name] = value
                    continue

                new_line = self.expand_defines(line, defines)

                if current_macro is None:
                    context.append(new_line)
                else:
                    current_macro.add(new_line)

            with open(output, "w") as fp:
                fp.write("".join(context))

            print("[Success] new compiled script %s has been generated!" % output)

    def run(self):
        src = self.opts.file
        dst = self.opts.out

        self.compile_script(src, dst)

if __name__ == "__main__":
    App().run()

