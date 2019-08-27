/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha512.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/07/24 18:00:02 by rcross            #+#    #+#             */
/*   Updated: 2019/07/24 18:00:06 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/ft_sha512.h"

void			sha512_r_algo(uint64_t *buff, uint64_t *tmp_words)
{
	uint64_t	i[7];

	i[0] = -1;
	while (++(i[0]) < 80)
	{
		i[1] = EP1(buff[E]);
		i[3] = CH(buff[E], buff[F], buff[G]);
		i[4] = buff[H] + i[1] + i[3] + g_constants[i[0]] + tmp_words[i[0]];
		i[2] = EP0(buff[A]);
		i[5] = MAJ(buff[A], buff[B], buff[C]);
		i[6] = i[2] + i[5];
		buff[H] = buff[G];
		buff[G] = buff[F];
		buff[F] = buff[E];
		buff[E] = buff[D] + i[4];
		buff[D] = buff[C];
		buff[C] = buff[B];
		buff[B] = buff[A];
		buff[A] = i[4] + i[6];
	}
}

void			exec_sha512_cycle(t_sha512 *sha512, uint8_t *word)
{
	int				chunk_num;
	uint64_t		buffer[8];
	static uint64_t	tmp_words[80];
	int				i;
	int				j;

	i = -1;
	chunk_num = sha512->len_bytes / 128;
	ft_bzero(tmp_words, 80 * sizeof(uint64_t));
	while (++i < chunk_num && (j = -1))
	{
		ft_memcpy(buffer, sha512->buffer, sizeof(buffer));
		init_tmp_words512(tmp_words, (uint64_t *)(word + i * 128));
		sha512_r_algo(buffer, tmp_words);
		while (++j < 8)
			sha512->buffer[j] += buffer[j];
	}
}

int				append_pad_bits_sha512(uint64_t *buf, uint32_t fsize)
{
	size_t		size;
	uint64_t	inp_bitlen;
	size_t		num_blocks;
	size_t		i;

	i = -1;
	inp_bitlen = 8 * fsize;
	size = inp_bitlen + 128;
	while (++size % 1024)
		;
	num_blocks = size / 1024;
	size % 1024 ? num_blocks++ : 0;
	((char*)buf)[fsize] = 0x80;
	while (++i < (num_blocks * 16) - 1)
		buf[i] = swap_int64(buf[i]);
	buf[((num_blocks * 1024 - 128) / 64) + 1] = inp_bitlen;
	return (num_blocks * 128);
}

uint64_t		*sha512_word(const char *word, t_sha512 *sha512, uint32_t fsize)
{
	uint8_t			*message;
	uint64_t		*digest;

	sha512->buffer[A] = 0x6a09e667f3bcc908;
	sha512->buffer[B] = 0xbb67ae8584caa73b;
	sha512->buffer[C] = 0x3c6ef372fe94f82b;
	sha512->buffer[D] = 0xa54ff53a5f1d36f1;
	sha512->buffer[E] = 0x510e527fade682d1;
	sha512->buffer[F] = 0x9b05688c2b3e6c1f;
	sha512->buffer[G] = 0x1f83d9abfb41bd6b;
	sha512->buffer[H] = 0x5be0cd19137e2179;
	sha512->len_bytes = calc_bytenum((size_t)(fsize + 9));
	message = ft_memalloc(sha512->len_bytes);
	ft_bzero(message, sha512->len_bytes);
	ft_memcpy(message, word, fsize);
	sha512->len_bytes = append_pad_bits_sha512((uint64_t *)message, fsize);
	sha512->len_bits = sha512->len_bytes * 8;
	exec_sha512_cycle(sha512, message);
	free(message);
	digest = ft_memalloc(sizeof(sha512->buffer));
	ft_memcpy(digest, sha512->buffer, sizeof(sha512->buffer));
	return (digest);
}

void			sha512(t_ssl *ssl)
{
	t_sha512	sha512;
	uint64_t	*res;
	int			index;

	index = -1;
	res = NULL;
	while (++index < ssl->p_size)
	{
		ft_bzero((void *)&sha512, sizeof(t_sha512 *));
		if (ssl->to_hash[index] != NULL)
			res = sha512_word(ssl->to_hash[index], &sha512, ssl->f_size[index]);
		output_64(ssl, res, index);
	}
}
