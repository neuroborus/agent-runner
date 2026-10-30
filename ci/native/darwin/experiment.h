/* Observed CI helper purpose is durable image data, never release approval. */
#ifndef NATIVE_DARWIN_EXPERIMENT_H
#define NATIVE_DARWIN_EXPERIMENT_H
#ifdef NATIVE_CI_EXPERIMENT
__attribute__((used, section("__TEXT,__nexp")))
const char native_experiment_purpose[] = "native-ci-experiment-v1";
#endif
#endif
