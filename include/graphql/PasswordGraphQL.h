#pragma once

#include <memory>
#include <string>
#include <nlohmann/json.hpp>

#include "graphql/PasswordSchema.h"  // тут есть class Operations

namespace graphql::password
{
    using Json = nlohmann::json;

    using ServicePtr = std::shared_ptr<graphql::service::Request>;

    // фабрика, собирающая Request + Operations
    ServicePtr build_service();

    std::string execute_graphql(
        const ServicePtr& service,
        const std::string& query,
        const std::string& operationName,
        const Json& variablesJson);
}
