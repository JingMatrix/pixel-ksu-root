#pragma once
/*
 * The cycle counter this side channel times with. One definition serves every
 * consumer, so a measurement taken here is comparable with one taken anywhere
 * else in the tree.
 *
 * Included by relative path, so a translation unit needs no include directory
 * of its own -- several consumers build with none.
 */
#include "../../base/timing.h"
