/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ssl.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/14 00:18:01 by rcross            #+#    #+#             */
/*   Updated: 2019/07/24 19:15:16 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_SSL_H
# define FT_SSL_H

# include "../libft/libft.h"
# include <unistd.h>
# include <stdlib.h>
# include <fcntl.h>
# include <stdio.h>

# ifndef MAX_FILES
#  define MAX_FILES 10
# endif

# ifndef SEG
#  define SEG -2
# endif

# ifndef TRUE
#  define TRUE 1
# endif

typedef struct	s_ssl_flags
{
	int			p;
	int			q;
	int			r;
	int			s;
}				t_ssl_flags;

typedef struct	s_ssl
{
	int			c_stdin;
	int			output;
	int			md5;
	int			sha256;
	int			sha224;
	int			sha512;
	int			sha384;
	int			p_size;
	char		**files;
	char		**to_hash;
	uint32_t	*f_size;
	t_ssl_flags	ssl_flags;
}				t_ssl;

void			ft_error(char *str);
void			ft_usage(char **argv);
void			init_ssl(t_ssl *ssl, int argc, char **argv);
void			get_input(t_ssl *ssl, char **argv);
void			md5(t_ssl *ssl);
void			sha256(t_ssl *ssl);
void			sha224(t_ssl *ssl);
void			sha512(t_ssl *ssl);
void			sha384(t_ssl *ssl);
void			output_32(t_ssl *ssl, uint32_t *hash, int i);
void			output_64(t_ssl *ssl, uint64_t *ret, int i);
void			print_digest_32(t_ssl *ssl, uint32_t *digest,
										uint32_t tmp, int i);
void			print_digest_64(t_ssl *ssl, uint64_t *digest,
										uint64_t tmp, int i);
void			print_digest_64_2(t_ssl *ssl, uint64_t *digest,
										uint64_t tmp, int i);

/*
**	BONUSES
**	- works with multiple flags after -s flag has been given
**	- sha256 also works with flags
**	- sha224
**	- sha224 also works with flags
**	- sha512
**	- sha512 also works with flags
**	- sha384
**	- sha384 also works with flags
*/

#endif
