compile = gcc

program = dns

csources = $(program).c

cobjects = $(csources:.c=.o)


$(program): $(cobjects)
	$(compile) -o $(program) $(cobjects)

clean:
	rm *.o
