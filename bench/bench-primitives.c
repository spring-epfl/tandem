/*
 * Computes exponentiation and pairing cost for the configured RELIC pairing
 * curve.
 */

#include <stdio.h>
#include "tandem.h"
#include <time.h>
#include <math.h>

#define NR_EXPERIMENTS 1000

int
main(int argc, char** argv) {
  // Initialize relic
  if( core_init() != RLC_OK ) {
    core_clean();
    printf("Error loading relic");
    return 1;
  }

  if( pc_param_set_any() != RLC_OK ) {
    printf("Error: No curve!");
    return 1;
  }

  pc_param_print();

  bn_t order;
  g1_get_ord(order);

  bn_t exps[NR_EXPERIMENTS];
  for(int i = 0; i < NR_EXPERIMENTS; i++) {
    bn_null(exps[i]);
    bn_new(exps[i]);
    bn_rand_mod(exps[i], order);
  }

  g1_t group1_bases[NR_EXPERIMENTS];
  g2_t group2_bases[NR_EXPERIMENTS];
  gt_t groupt_bases[NR_EXPERIMENTS];
  g1_t group1_elts[NR_EXPERIMENTS];
  g2_t group2_elts[NR_EXPERIMENTS];
  gt_t groupt_elts[NR_EXPERIMENTS];
  for(int i = 0; i < NR_EXPERIMENTS; i++) {
    g1_null(group1_bases[i]);
    g1_new(group1_bases[i]);
    g1_rand(group1_bases[i]);

    g2_null(group2_bases[i]);
    g2_new(group2_bases[i]);
    g2_rand(group2_bases[i]);

    gt_null(groupt_bases[i]);
    gt_new(groupt_bases[i]);
    gt_rand(groupt_bases[i]);

    g1_null(group1_elts[i]);
    g1_new(group1_elts[i]);

    g2_null(group2_elts[i]);
    g2_new(group2_elts[i]);

    gt_null(groupt_elts[i]);
    gt_new(groupt_elts[i]);
  }

  time_t tic, toc;
  tic = clock();
  for(int i = 0; i < NR_EXPERIMENTS; i++) {
    g1_mul(group1_elts[i], group1_bases[i], exps[i]);
  }
  toc = clock();
  double g1_exp_time = (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS;
  printf("Time for G1 exponentiation (various bases): %e s\n", g1_exp_time);

  tic = clock();
  for(int i = 0; i < NR_EXPERIMENTS; i++) {
    g2_mul(group2_elts[i], group2_bases[i], exps[i]);
  }
  toc = clock();
  double g2_exp_time = (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS;
  printf("Time for G2 exponentiation (various bases): %e s\n", g2_exp_time);

  tic = clock();
  for(int i = 0; i < NR_EXPERIMENTS; i++) {
    gt_exp(groupt_elts[i], groupt_bases[i], exps[i]);
  }
  toc = clock();
  double gt_exp_time = (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS;
  printf("Time for GT exponentiation (various bases): %e s\n", gt_exp_time);

  tic = clock();
  for(int i = 0; i < NR_EXPERIMENTS; i++) {
    pc_map(groupt_elts[i], group1_bases[i], group2_bases[i]);
  }
  toc = clock();
  double pair_time = (double)(toc - tic) / CLOCKS_PER_SEC / NR_EXPERIMENTS;
  printf("Time for pairing computation: %e s\n", pair_time);

  return 0;
}
