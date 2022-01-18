# windows_fuzzing_harness
Template harness for fuzzing Windows binaries using WinAFL or Jackalope in shared memory mode. The code is heavily commented but will not run out of the box. More specifically, you will need to configure it to load your target binary, and provide the offset (or use GetProcAddress) of your target function.

I have also created a loader script, available at https://gist.github.com/australeo/ab710af5829b791dbe70726c8fb18110 which can be used to check that your harness works as intended with a given file sample.
