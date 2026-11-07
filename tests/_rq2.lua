-- debug: co vlastne dela require na miner.test
local src = readfile and nil -- placeholder
local chunk = assert((loadstring or load)(nil))
