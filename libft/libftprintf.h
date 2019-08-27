/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libftprintf.h                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: rcross <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/04 18:18:01 by rcross            #+#    #+#             */
/*   Updated: 2019/06/27 17:13:00 by rcross           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFTPRINTF_H
# define LIBFTPRINTF_H

# include "libft.h"
# include <unistd.h>
# include <stdlib.h>
# include <stdarg.h>

/*
**	flag_mask: "-+ 0#"
**	length_mask: "lhL"
**	conversion_mask: "sScdiuoxXpfeEbr%"
*/

typedef struct		s_printf
{
	va_list			ap;
	char			*format2;
	int				i;
	int				len;
	char			flag[6];
	char			length[3];
	char			conversion;
	long int		field_width;
	long int		precision;
	char			*flag_mask;
	char			*length_mask;
	char			*conversion_mask;
}					t_printf;

int					ft_printf(const char *format, ...);
void				get_tags(t_printf *data);
void				padding(t_printf *data, char c, int len, int update_len);
void				padding2(char to_print, int *count, int spaces);
void				parse_conversion(t_printf *data);
void				parse_length(t_printf *data);
void				parse_precision(t_printf *data);
void				parse_field_width(t_printf *data);
void				parse_flags(t_printf *data);
void				convert_o(t_printf *data);
void				convert_i(t_printf *data);
void				convert_c(t_printf *data);
void				convert_f(t_printf *data);
void				convert_p(t_printf *data);
void				convert_s(t_printf *data);
void				convert_u(t_printf *data);
void				convert_x(t_printf *data);
void				convert_b(t_printf *data);
void				convert_r(t_printf *data);
void				convert_e(t_printf *data);
void				convert_percent(t_printf *data);
void				ft_intmove(char *str, int len, unsigned long long number,
													int negative);
void				put_float(t_printf *data, long double number);
int					get_width(t_printf *data, char *result, char *to_print);
int					*get_roman_decimals(void);
char				**get_roman_symbols(void);
void				put_num_e(t_printf *data, long double number, int *count);

#endif
