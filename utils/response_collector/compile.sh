g++ -c main.cpp functions.cpp
g++ -o response_collector -lvdns main.o functions.o
rm *.o
