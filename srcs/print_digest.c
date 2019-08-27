/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   print_digest.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/16 23:24:32 by rcross            #+#    #+#             */
/*   Updated: 2019/07/24 18:57:54 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_ssl.h"

static uint32_t	swap_int32(const uint32_t value)
{
	uint32_t result;

	result = 0;
	result |= (value & 0x000000FF) << 24;
	result |= (value & 0x0000FF00) << 8;
	result |= (value & 0x00FF0000) >> 8;
	result |= (value & 0xFF000000) >> 24;
	return (result);
}

void			print_digest_64(t_ssl *ssl, uint64_t *digest,
									uint64_t tmp, int i)
{
	if (ssl->sha256)
	{
		while (++i < 32 / 4)
		{
			tmp = digest[i];
			ft_printf("%08.8x", tmp);
		}
	}
	else if (ssl->sha224)
	{
		while (++i < 28 / 4)
		{
			tmp = digest[i];
			ft_printf("%08.8x", tmp);
		}
	}
	else
		print_digest_64_2(ssl, digest, tmp, i);
}

void			print_digest_64_2(t_ssl *ssl, uint64_t *digest,
									uint64_t tmp, int i)
{
	if (ssl->sha512)
	{
		while (++i < 32 / 4)
		{
			tmp = digest[i];
			ft_printf("%16.16llx", tmp);
		}
	}
	else if (ssl->sha384)
	{
		while (++i < 24 / 4)
		{
			tmp = digest[i];
			ft_printf("%16.16llx", tmp);
		}
	}
}

void			print_digest_32(t_ssl *ssl, uint32_t *digest,
									uint32_t tmp, int i)
{
	if (ssl->md5)
	{
		while (++i < 16 / 4)
		{
			tmp = digest[i];
			tmp = swap_int32(tmp);
			ft_printf("%08.8x", tmp);
		}
	}
}
