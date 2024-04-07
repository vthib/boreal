Write-Host "compiling types.exe..."
csc.exe /unsafe types.cs

Write-Host "compiling types2.dll..."
ilasm.exe /dll /noautoinherit types2.cil

Write-Host "compiling assembly.dll..."
ilasm.exe /dll assembly.cil

Write-Host "compiling classes.dll..."
csc.exe /target:library /platform:x64 classes.cs

Write-Host "compiling constants.exe..."
csc.exe /platform:x64 /r:MyClasses=classes.dll constants.cs