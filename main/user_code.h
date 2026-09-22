/*
 * The two entry points of user_code.cpp, declared so main.c (plain C) can
 * start them. Edit user_code.cpp, not this file.
 */

#ifndef USER_CODE_H_
#define USER_CODE_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Runs once, when the task starts. Your Arduino setup(). */
void user_setup(void);

/* Runs again and again, forever. Your Arduino loop(). */
void user_loop(void);

#ifdef __cplusplus
}
#endif

#endif /* USER_CODE_H_ */
