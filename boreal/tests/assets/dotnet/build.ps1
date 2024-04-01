Write-Host "compiling types.exe..."
csc.exe /unsafe types.cs

Write-Host "compiling types2.dll..."
ilasm.exe /dll /noautoinherit types2.cil