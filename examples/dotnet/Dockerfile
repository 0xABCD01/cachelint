# A .NET service that restores NuGet packages after copying the whole source,
# so `dotnet restore` re-runs on every code change. cachelint copies the
# project file(s) first instead. Run `cachelint examples/dotnet`.
FROM mcr.microsoft.com/dotnet/sdk:8.0
WORKDIR /src

COPY . .
RUN dotnet restore
RUN dotnet publish -c Release -o /app

ENTRYPOINT ["dotnet", "/app/WebApp.dll"]
