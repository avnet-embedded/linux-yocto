#ifndef _MRVL_LOKI_H_
#define _MRVL_LOKI_H_

typedef int (*connip_irq_cb_t)(uint32_t instance, uint32_t pss_int);

int mrvl_loki_register_irq_cb(connip_irq_cb_t func);
void mrvl_loki_unregister_irq_cb(void);

#endif /* _MRVL_LOKI_H_ */
