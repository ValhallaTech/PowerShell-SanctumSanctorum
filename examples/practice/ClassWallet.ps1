class Wallet
    {
        [string] $NameOnID
        [string] $CreditCardBank
        [float] $creditCardBalance
        [string] $DebitCardBank
        [float] $DebitCardAvailableFunds
        [int] $CashOnHand

        [void] SpendCash([float]$Spent) {
            $this.CashOnHand -= $Spent
        }
    }

$FredWallet.CreditCardBank='Wells Fargo'
$FredWallet.CreditCardBalance=1337.69
$FredWallet.DebitCardBank='Wells Fargo'
$FredWallet.DebitCardAvailableFunds=2069.69
$FredWallet.CashOnHand= 169
