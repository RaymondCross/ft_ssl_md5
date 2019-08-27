# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: rcross <marvin@42.fr>                      +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/02/27 14:12:57 by rcross            #+#    #+#              #
#    Updated: 2019/07/17 21:59:23 by rcross           ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = libft.a

SRCS =	ft_atoi.c\
		ft_bzero.c\
		ft_isalnum.c\
		ft_isalpha.c\
		ft_isascii.c\
		ft_isdigit.c\
		ft_isprint.c\
		ft_memccpy.c\
		ft_memchr.c\
		ft_memcmp.c\
		ft_memcpy.c\
		ft_memmove.c\
		ft_memset.c\
		ft_strcat.c\
		ft_strchr.c\
		ft_strcmp.c\
		ft_strcpy.c\
		ft_strdup.c\
		ft_strlcat.c\
		ft_strlen.c\
		ft_strncat.c\
		ft_strncmp.c\
		ft_strncpy.c\
		ft_strnstr.c\
		ft_strrchr.c\
		ft_strstr.c\
		ft_tolower.c\
		ft_toupper.c\
		ft_memalloc.c\
		ft_memdel.c\
		ft_strnew.c\
		ft_strdel.c\
		ft_strclr.c\
		ft_striter.c\
		ft_striteri.c\
		ft_strmap.c\
		ft_strmapi.c\
		ft_strequ.c\
		ft_strnequ.c\
		ft_strsub.c\
		ft_strjoin.c\
		ft_strtrim.c\
		ft_strsplit.c\
		ft_itoa.c\
		ft_putchar.c\
		ft_putstr.c\
		ft_putendl.c\
		ft_putnbr.c\
		ft_putchar_fd.c\
		ft_putstr_fd.c\
		ft_putendl_fd.c\
		ft_putnbr_fd.c\
		ft_lstnew.c\
		ft_lstdelone.c\
		ft_lstdel.c\
		ft_lstadd.c\
		ft_lstiter.c\
		ft_lstmap.c\
		ft_str_isalnum.c\
		ft_str_isalpha.c\
		ft_str_isascii.c\
		ft_str_isdigit.c\
		ft_str_islowercase.c\
		ft_str_isuppercase.c\
		ft_islowercase.c\
		ft_isuppercase.c\
		ft_iswhitespace.c\
		get_next_line.c\
		ft_sqrt.c\
		ft_wordcount.c\
		ft_wordlen.c\
		ft_mapdel.c\
		ft_update.c\
		ft_strcon.c\
		ft_mapalloc.c\
		ft_swap.c\
		ft_strndup.c\
		ft_putnbrmax.c\
		ft_itoa_base_upper.c\
		ft_itoa_base_lower.c\
		ft_nbrlen.c\
		ft_numlen.c\
		ft_strrev.c\
		ft_charswap.c\
		ft_binary_add.c\
		ft_str_to_upper.c\
		ft_numlen_base.c\
		ft_free_2d.c\
		ft_printf/e_helper.c\
		ft_printf/ft_printf.c\
		ft_printf/get_tags.c\
		ft_printf/num_helper.c\
		ft_printf/padding.c\
		ft_printf/parse.c\
		ft_printf/roman.c\
		ft_printf/conversions/convert_b.c\
		ft_printf/conversions/convert_c.c\
		ft_printf/conversions/convert_e.c\
		ft_printf/conversions/convert_f.c\
		ft_printf/conversions/convert_i.c\
		ft_printf/conversions/convert_o.c\
		ft_printf/conversions/convert_p.c\
		ft_printf/conversions/convert_percent.c\
		ft_printf/conversions/convert_r.c\
		ft_printf/conversions/convert_s.c\
		ft_printf/conversions/convert_u.c\
		ft_printf/conversions/convert_x.c\
		ft_memrev.c\

OBJECTS = *.o

FLAGS = -Wall -Werror -Wextra

all: $(NAME)

$(NAME):
		gcc $(FLAGS) -c $(SRCS) -I libft.h
		ar rc $(NAME) $(OBJECTS)
		ranlib $(NAME)
		@rm -f $(OBJECTS)

clean:
		@rm -f $(OBJECTS)

fclean: clean
		@rm -f $(NAME)
		@rm -f a.out

re: fclean all
