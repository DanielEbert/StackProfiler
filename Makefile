CXX=g++-9
CXXFLAGS=-g -finstrument-functions -no-pie

all: test

trace.o: trace.cpp
	$(CXX) -c -o $@ $<

test.o: test.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS)

test: test.o trace.o
	$(CXX) -o $@ $^ $(CXXFLAGS)

.PHONY: clean
clean:
	rm -f *.o test