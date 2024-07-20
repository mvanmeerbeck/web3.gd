extends Node2D

var web3_client : Web3 = null

# Called when the node enters the scene tree for the first time.
func _ready():
	web3_client = Web3.new("http://localhost:8545")
	pass # Replace with function body.


# Called every frame. 'delta' is the elapsed time since the previous frame.
func _process(delta):
	pass
