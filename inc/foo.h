/**
 * @file foo.h
 *
 * The example header file for foo
 *
 * Copyright (C) Advanced Space LLC
 * All Rights Reserved
 * Unauthorized copying of any file in this repository via any medium is
 * strictly prohibited. Everything in this repository is proprietary and
 * confidential.
 *
 * Author: Kirk Roerig [kroerig@advancedspace.com]
 */

#ifndef __FOO_H__

/**
 * @brief This is just an example function
 *
 * @detail This is illustrating the type of documentation
 * format that we expect.
 *
 * @param[in] i Some parameter input
 * @param[in,out] j Some parameter pointer to a number that will input and
 * output a value
 *
 * @return Sum of parameters i and *j
 */
float foo (float i, float* j);

#endif
