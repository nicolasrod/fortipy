# FortiPY

FortiPY is a Fortify FPR file explorer library.

## Use examples

There is basically two ways to open an FPR (of FVDL file):


```
import fortipy

with fortipy.FPR("filename.fpr") as f:
    print f.get_types_of_vulns()
```

or you can use the standard open/close:

```
import fortipy

f = fortipy.FPR("filename.fpr")
print f.get_types_of_vulns()
f.close()   

# by default if you open an .fpr file close() will clean the temp files but you can override this:
# f.close(clean=False)
```

Once opened, the object will contain the information from the FPR file in Python structures:

```

# print the license_info
print(f.engine_data.license_info)

# print all vulns of type "Dead Code"
print(f.get_vulns_of_type("dead code"))

# print all functions called with no definitions in the code base
print(f.called_with_no_def)

# for each snippet of code, print its id, the filename, and the start and end line of it
for snippet in f.snippets:
    print("=" * 60)
    print(snippet.id, snippet.file, snippet.line_start, snippet.line_end)
    print(snippet.text)

# print the machine_info from where the scan was executed
print(f.engine_data.machine_info)
```

Still need to document a lot of things and complete the sink/source paths (in case you want the complete trace of the
result from Fortify -I personally rarely used it-) so there's some work that needs to be done.