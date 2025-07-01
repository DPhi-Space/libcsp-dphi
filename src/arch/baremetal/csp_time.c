#include "csp/arch/csp_time.h"

extern uint32_t ms_from_boot;

uint32_t csp_get_ms(void)
{
	return ms_from_boot;
}

uint32_t csp_get_ms_isr(void)
{
	return csp_get_ms();
}

uint32_t csp_get_s(void)
{
	return csp_get_ms() / 1000;
}

uint32_t csp_get_s_isr(void)
{
	return csp_get_s();
}
