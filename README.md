# StackProfiler

```bash
make
./main.py ./test
./test
```

### Notes

By looking at previous 'stackDepth - 1', an comparing the sp offset, we can see how much memory we need.

- filter likely by going left to right, creating stacktraces, filtering out duplicates.
