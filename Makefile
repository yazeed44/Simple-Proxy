CFLG=-O3 -Wall -std=c++17 -lpthread 

webproxy:webproxy.cpp
	g++ $(CFLG) -o webproxy $^

clean:
	rm -f webproxy *.o *.a
