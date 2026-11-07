local M = require("../miner.test")
print("type:", type(M))
if type(M) == "string" then print("obsah:", M:sub(1, 120)) end
