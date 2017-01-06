#ifndef BLOCK_SEMANTICS_H
#define BLOCK_SEMANTICS_H

#include "expression.h"
#include "state.h"

extern "C" {
#include <valgrind/libvex.h>
#include <valgrind/libvex_ir.h>
}

#include <map>
#include <unordered_map>

#define arg_out
class BlockSemantics;

typedef ExpressionPtr (BlockSemantics::*ExpressionParser)(const IRExpr&);
typedef bool (BlockSemantics::*StatementHandler)(const IRStmt&);

// TODO: Handle calls, calling conventions (System-V for now).
// FIXME: This class is infected with shared_ptr:s, consider boost::variant.

class Block;

/*!
 * \brief Class computing the effective semantics of a given `Block`.
 *
 * \todo Allow sub-classes of this class at every point where this class is
 * currently use. This enables a user to implement custom semantics.
 */
class BlockSemantics {
private:
    State &_state;
    const Block &_block;
    std::shared_ptr<Unknown> _unknown;

    static const std::map<IRExprTag, ExpressionParser> _expression_parser;
    static const std::map<IRStmtTag, StatementHandler> _statement_handler;

public:
    BlockSemantics() = delete;
    BlockSemantics(const BlockSemantics&) = delete;
    void operator=(const BlockSemantics&) = delete;

    BlockSemantics(const Block &block, State &initial_state);

    /*!
     * \brief Getter to access the computed state.
     * \return Returns the computed semantics in form of a `State` reference.
     */
    const State &get_state() const {
        return _state;
    }

private:
    bool extract_semantics(const IRSB &block);

    ExpressionPtr parse_expression(const IRExpr &expression);
    bool handle_statement(const IRStmt &statement);

    uint64_t get_mask(uint8_t size) const;
    bool get_size(const IRType &type, arg_out uint8_t &size) const;
    bool parse_type(const IRType &type, arg_out uint8_t &size,
                    arg_out uint64_t &mask) const;

    // Expression parsers.
    ExpressionPtr parse_get(const IRExpr &expression);
    ExpressionPtr parse_geti(const IRExpr &expression);

    ExpressionPtr parse_rdtmp(const IRExpr &expression);

    ExpressionPtr parse_qop(const IRExpr &expression);
    ExpressionPtr parse_triop(const IRExpr &expression);
    ExpressionPtr parse_binop(const IRExpr &expression);
    ExpressionPtr parse_unop(const IRExpr &expression);

    ExpressionPtr parse_load(const IRExpr &expression);
    ExpressionPtr parse_const(const IRExpr &expression);

    ExpressionPtr parse_ccall(const IRExpr &expression);
    ExpressionPtr parse_ite(const IRExpr &expression);

    // Statement handlers.
    bool handle_noop(const IRStmt &statement);
    bool handle_put(const IRStmt &statement);
    bool handle_puti(const IRStmt &statement);
    bool handle_wrtmp(const IRStmt &statement);
    bool handle_store(const IRStmt &statement);
    bool handle_storeg(const IRStmt &statement);
    bool handle_loadg(const IRStmt &statement);
    bool handle_abi_hint(const IRStmt &statement);
};

#endif // BLOCK_SEMANTICS_H
