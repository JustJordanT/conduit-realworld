FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["Conduit.API/Conduit.API.csproj", "Conduit.API/"]
RUN dotnet restore "Conduit.API/Conduit.API.csproj"
COPY . .
WORKDIR "/src/Conduit.API"
RUN dotnet build "Conduit.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Conduit.API.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Conduit.API.dll"]
