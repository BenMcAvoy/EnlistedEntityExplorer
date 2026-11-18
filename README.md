# EnlistedEntityExplorer

EnlistedEntityExplorer is a Windows C++ reverse-engineering experiment focused on the Dagor ECS entity layout used by *Enlisted* single-player. The code explores entity descriptors, IDs, template names and transform data using notes from static analysis.

## Build

Open `EnlistedEntityExplorer.sln` in Visual Studio and build the x64 configuration.

## Status

This is an incomplete research prototype, not a released entity browser. The offsets are version-specific and the archetype-array address is still a placeholder in the source, so parts of the data walk are unfinished.
