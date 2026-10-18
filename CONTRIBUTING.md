# Contributing to GoOffline

Thanks for being here. Issues and PRs are welcome.

## Build

Requires the [.NET 8 SDK](https://dotnet.microsoft.com/download) and (for Hard mode)
Visual Studio C++ build tools.

```powershell
# Native hook DLL (x64 + x86)
./native/GoOfflineHook/build.ps1

# Single-file exe
dotnet publish src/GoOffline -c Release -o publish
```

Then `publish/GoOffline.exe` is the shippable binary.

## Project layout

```
src/GoOffline/            WPF app (C#, .NET 8)
  Services/               Firewall, process, injection, store
  Models/                 Data types
  MainWindow.xaml[.cs]    Main window
  PickerWindow.xaml[.cs]  "Add program" picker
native/GoOfflineHook/     C++ hook DLL (IAT patcher)
docs/                     GitHub Pages site
.github/workflows/        Release automation
assets/                   Logo and marketing art
```

## Pull requests

Small, focused changes are easier to review than big ones. If you're adding a feature,
open a short issue first so we can agree on the shape before you spend time on it.

Please run the app once before submitting — the app isn't covered by unit tests, so
visual confirmation is the backstop.

## Code style

- One concern per file.
- Comments explain *why*, not *what*.
- Match the style of the surrounding code.

## Reporting bugs

Open an issue using the Bug report template. Include the program you were blocking,
whether Hard mode was on, your Windows version, and the message from GoOffline's status bar.
