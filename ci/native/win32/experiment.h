/* Local CI images carry a durable purpose marker. It is not a signature or
 * publication approval; reviewed readers must reject these images. */
#ifndef NATIVE_WINDOWS_EXPERIMENT_H
#define NATIVE_WINDOWS_EXPERIMENT_H
#ifdef NATIVE_CI_EXPERIMENT
#pragma section(".nexp", read)
__declspec(allocate(".nexp")) const char native_experiment_purpose[] =
  "native-ci-experiment-v1";
#pragma comment(linker, "/include:native_experiment_purpose")
#endif
#endif
