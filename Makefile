NAME	:= ft_ssl
DNAME	:= d_$(NAME)

CC		:= gcc

CFLAGS	:= -Wall -Wextra -Werror
DFLAGS	:= -Wall -Wextra -g

FILES	:= main.c\
			init.c\
			md5.c\
			sha256.c\
			sha256_helper.c\
			sha224.c\
			sha224_helper.c\
			sha512.c\
			sha512_helper.c\
			sha384.c\
			sha384_helper.c\
			output_32.c\
			output_64.c\
			print_digest.c\

SRC		:= $(addprefix srcs/, $(FILES))

OBJ		:= $(SRC:.c=.o)

LIBFT	:= libft/libft.a
LIB		:= -I libft/ $(LIBFT)

all: $(NAME)

$(NAME):
	@$(CC) $(CFLAGS) $(LIB) $(SRC) -o $(NAME)
	@echo "Creating ./$(NAME)"

libft:
	@echo "Making libft"
	@make -sC libft re

d:
	@echo "Making debug"
	$(CC) $(DFLAGS) $(LIB) $(SRC) -o $(DNAME)

clean:
	@rm -f $(OBJ)
	@echo "Removing objects"

dclean:
	@echo "Removing ./$(DNAME)"
	@rm -rf $(DNAME) $(DNAME).dSYM/

fclean: clean
	@echo "Removing ./$(NAME)"
	@rm -f $(NAME)

re: fclean all

.PHONY: all libft d clean dclean fclean re
