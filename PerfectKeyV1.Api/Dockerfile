# See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

# This stage is used when running from VS in fast mode (Default for Debug configuration)
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081


# This stage is used to build the service project
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["PerfectKeyV1.Api/PerfectKeyV1.Api.csproj", "PerfectKeyV1.Api/"]
COPY ["PerfectKeyV1.Application/PerfectKeyV1.Application.csproj", "PerfectKeyV1.Application/"]
COPY ["PerfectKeyV1.Domain/PerfectKeyV1.Domain.csproj", "PerfectKeyV1.Domain/"]
COPY ["PerfectKeyV1.Infrastructure/PerfectKeyV1.Infrastructure.csproj", "PerfectKeyV1.Infrastructure/"]
RUN dotnet restore "./PerfectKeyV1.Api/PerfectKeyV1.Api.csproj"
COPY . .
WORKDIR "/src/PerfectKeyV1.Api"
RUN dotnet build "./PerfectKeyV1.Api.csproj" -c $BUILD_CONFIGURATION -o /app/build

# This stage is used to publish the service project to be copied to the final stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./PerfectKeyV1.Api.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# This stage is used in production or when running from VS in regular mode (Default when not using the Debug configuration)
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "PerfectKeyV1.Api.dll"]