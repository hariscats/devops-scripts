# Python script for debugging code

import sys
import trace

def trace_calls(frame, event, arg):
    """Trace function to log calls to other functions."""
    if event != "call":
        return
    co = frame.f_code
    func_name = co.co_name
    if func_name == 'write':
        # Ignore write() calls from printing
        return
    line_no = frame.f_lineno
    filename = co.co_filename
    print(f"Call to {func_name} on line {line_no} of {filename}")
    return trace_calls

def trace_lines(frame, event, arg):
    """Trace function to log executed lines within functions."""
    if event != 'line':
        return
    co = frame.f_code
    func_name = co.co_name
    line_no = frame.f_lineno
    filename = co.co_filename
    line = linecache.getline(filename, line_no)
    print(f"{func_name} line {line_no}: {line.strip()}")

def run_trace(file):
    """Set up tracing and execute the specified Python script."""
    # The trace.Trace() class can be used with various trace options.
    tracer = trace.Trace(
        trace=True,  # Set true if you want to trace lines executed
        count=False  # Set false unless you need to count executions per line
    )
    tracer.runfunc(execfile, file)

def execfile(file):
    """Execute the given Python file after compiling its source."""
    with open(file) as f:
        code = compile(f.read(), file, 'exec')
        exec(code, {'__name__': '__main__'})

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debug_script.py scriptname.py")
    else:
        sys.settrace(trace_calls)  # Set the trace function
        run_trace(sys.argv[1])
