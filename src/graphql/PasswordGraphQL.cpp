#include "graphql/PasswordGraphQL.h"

#include "graphqlservice/GraphQLParse.h"
#include "graphqlservice/JSONResponse.h"

#include "graphql/PasswordSchema.h"
#include "graphql/QueryObject.h"
#include "graphql/MutationObject.h"
#include "graphql/GeneratedPasswordObject.h" // <- нужен для object::GeneratedPassword

#include <string>
#include <vector>

namespace graphql::password
{
    using namespace graphql;

    // -------------------------
    // Query impl: ping
    // -------------------------
    struct QueryImpl
    {
        // Можно и без params, генератор сам подстроится
        std::string getPing() const
        {
            return "pong";
        }
    };

    // -------------------------
    // GeneratedPassword impl
    // -------------------------
    struct GeneratedPasswordImpl
    {
        GeneratedPasswordImpl(std::string value, int length, std::string strength)
            : _value(std::move(value))
            , _length(length)
            , _strength(std::move(strength))
        {}

        std::string getValue() const { return _value; }
        int getLength() const { return _length; }
        std::string getStrength() const { return _strength; }

    private:
        std::string _value;
        int _length{};
        std::string _strength;
    };

    static std::string generate_password_gql(int length, bool useDigits, bool useSymbols)
    {
        std::string pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (useDigits)  pool += "0123456789";
        if (useSymbols) pool += "!@#$%^&*()-_=+[]{};:,.<>/?";

        if (length < 4) length = 4;
        if (length > 1024) length = 1024;

        std::string out;
        out.resize(static_cast<size_t>(length));

        // криптостойкость можно потом прикрутить через libsodium, но сейчас задача: чтобы жило и работало
        for (int i = 0; i < length; ++i)
        {
            out[static_cast<size_t>(i)] = pool[static_cast<size_t>(i) % pool.size()];
        }
        return out;
    }

    // -------------------------
    // Mutation impl: generatePassword
    // -------------------------
    struct MutationImpl
{
    std::shared_ptr<object::GeneratedPassword> applyGeneratePassword(GeneratePasswordInput input) const
    {
        const int len = input.length;
        const auto pw = generate_password_gql(len, input.useDigits, input.useSymbols);

        // “strength” можешь считать как хочешь, пока просто сделаем метку
        std::string strength = (len >= 20) ? "STRONG" : (len >= 12 ? "MEDIUM" : "WEAK");

        auto dto = std::make_shared<GeneratedPasswordImpl>(pw, len, std::move(strength));
        return std::make_shared<object::GeneratedPassword>(std::move(dto));
    }
};


    ServicePtr build_service()
    {
        // 1) Создаём impl
        auto queryImpl    = std::make_shared<QueryImpl>();
        auto mutationImpl = std::make_shared<MutationImpl>();

        // 2) Operations сам обернёт impl в object::Query/object::Mutation и сам возьмёт GetSchema()
        return std::make_shared<Operations>(queryImpl, mutationImpl);
    }

    std::string execute_graphql(
        const ServicePtr& service,
        const std::string& query,
        const std::string& operationName,
        const Json& variablesJson)
    {
        peg::ast queryAst = peg::parseString(query);
        queryAst.validated = true;

        response::Value variables(response::Type::Map);
        if (!variablesJson.is_null() && !variablesJson.empty())
        {
            variables = response::parseJSON(variablesJson.dump());
        }

        service::RequestResolveParams params{
            queryAst,
            operationName,
            std::move(variables)
        };

        auto result = service->resolve(std::move(params)).get();
        return response::toJSON(std::move(result));
    }
}
