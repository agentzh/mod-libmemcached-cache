module RestyScript (
    SqlVal(..),
    readView
) where

import Text.ParserCombinators.Parsec
import Data.List (intercalate)
import Numeric (showFloat)
import Text.Printf (printf)

data SqlVal = Select [SqlVal]
            | From [SqlVal]
            | Where SqlVal
            | Column SqlVal
            | Model SqlVal
            | Symbol String
            | QualifiedColumn (SqlVal, SqlVal)
            | Integer Integer
            | Float Double
            | String String
            | Variable (String)
            | FuncCall (String, [SqlVal])
            | RelExpr (String, SqlVal, SqlVal)
            | OrExpr [SqlVal]
            | AndExpr [SqlVal]
            | NullClause
                deriving (Ord, Eq, Show)

quote :: Char -> String -> String
quote sep s = [sep] ++ quoteChars s ++ [sep]
              where quoteChars (x:xs) =
                        if x == sep || x == '\\'
                            then x : x : quoteChars xs
                            else case lookup x escapes of
                                Just r -> r ++ quoteChars xs
                                Nothing -> x : quoteChars xs
                    quoteChars [] = ""

quoteLiteral :: String -> String
quoteLiteral = quote '\''

quoteIdent :: String -> String
quoteIdent = quote '"'

emitSql :: SqlVal -> String
emitSql (String s) = quoteLiteral s
emitSql (Select cols) = "select " ++ (intercalate ", " $ map emitSql cols)
emitSql (From models) = "from " ++ (intercalate ", " $ map emitSql models)
emitSql (Where cond) = "where " ++ (emitSql cond)
emitSql (Model model) = emitSql model
emitSql (Column col) = emitSql col
emitSql (Symbol name) = quoteIdent name
emitSql (Integer int) = show int
emitSql (Float float) = printf "%0f" float
emitSql (OrExpr args) = "(" ++ (intercalate " or " $ map emitSql args) ++ ")"
emitSql (AndExpr args) = "(" ++ (intercalate " and " $ map emitSql args) ++ ")"
emitSql (RelExpr (op, lhs, rhs)) = "(" ++ (emitSql lhs) ++ " " ++ op ++ " " ++ (emitSql rhs) ++ ")"
emitSql (NullClause) = ""

readView :: String -> String -> Either String [String]
readView file input = case parse parseView file input of
                        Left err -> Left $ show err
                        Right vals -> Right [dump show vals, dump emitSql vals]
                        where dump f lst = unwords $ map f lst

parseView :: Parser [SqlVal]
parseView = do select <- parseSelect
               from <- parseFrom
               whereClause <- parseWhere
               return $ filter (\x->x /= NullClause)
                            [select, from, whereClause]

{-
          <|> parseLimit
          <|> parseOffset
          <|> parseGroupBy
          <|> parseOrderBy
          <?> "SQL clause"
-}

parseFrom :: Parser SqlVal
parseFrom = do string "from" >> many1 space
               models <- sepBy1 parseModel listSep
               return $ From models
        <|> (return $ NullClause)
        <?> "from clause"

parseModel :: Parser SqlVal
parseModel = do model <- symbol
                spaces
                return $ Model $ Symbol model

symbol :: Parser String
symbol = do x <- letter
            xs <- many alphaNum
            return (x:xs)

listSep :: Parser ()
listSep = opSep ","

parseSelect :: Parser SqlVal
parseSelect = do string "select" >> many1 space
                 cols <- sepBy1 parseColumn listSep
                 return $ Select cols
          <?> "select clause"

parseColumn :: Parser SqlVal
parseColumn = do column <- symbol
                 spaces
                 return $ Column $ Symbol column
          <?> "column"

parseWhere :: Parser SqlVal
parseWhere = do string "where" >> many1 space
                cond <- parseOr
                return $ Where cond
         <|> (return $ NullClause)
         <?> "where clause"

parseOr :: Parser SqlVal
parseOr = do args <- sepBy1 parseAnd (opSep "or")
             return $ OrExpr args

opSep :: String -> Parser ()
opSep op = string op >> spaces

parseAnd :: Parser SqlVal
parseAnd = do args <- sepBy1 parseRel (opSep "and")
              return $ AndExpr args

parseRel :: Parser SqlVal
parseRel = do lhs <- parseTerm
              op <- relOp
              spaces
              rhs <- parseTerm
              return $ RelExpr (op, lhs, rhs)
         <?> "comparison expression"

relOp :: Parser String
relOp = string "="
         <|> try (string ">=")
         <|> string ">"
         <|> try (string "<=")
         <|> try (string "<>")
         <|> string "<"
         <|> string "like"

parseTerm :: Parser SqlVal
parseTerm = parseColumn
        <|> parseNumber
        <|> parseString
        <?> "term"

parseNumber :: Parser SqlVal
parseNumber = try (parseFloat)
          <|> do int <- many1 digit
                 spaces
                 return $ Integer $ read int
          <?> "number"

parseFloat :: Parser SqlVal
parseFloat = do int <- many1 digit
                char '.'
                dec <- many digit
                spaces
                return $ Float $ read (int ++ "." ++ noEmpty dec)
         <|> do char '.'
                dec <- many1 digit
                return $ Float $ read ("0." ++ dec)
         <?> "floating-point number"
         where noEmpty s = if s == "" then "0" else s

parseString :: Parser SqlVal
parseString = do char '\''
                 s <- many $ quotedChar '\''
                 char '\''
                 spaces
                 return $ String s
          <?> "string"

unescapes :: [(Char, Char)]
unescapes = zipWith pair "bnfrt" "\b\n\f\r\t"
    where pair a b = (a, b)

escapes :: [(Char, String)]
escapes = zipWith ch "\b\n\f\r\t" "bnfrt"
    where ch a b = (a, '\\':[b])

quotedChar :: Char -> Parser Char
quotedChar c = do char '\\'
                  c <- anyChar
                  return $ case lookup c unescapes of
                            Just r -> r
                            Nothing -> c
           <|> noneOf [c]
           <|> do try (string [c,c])
                  return c
