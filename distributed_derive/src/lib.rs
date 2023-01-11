use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream, Result},
    parse_macro_input, parse_quote,
    Expr, ItemFn, fold::{Fold, self},
};

struct Args {
    name: Option<Expr>,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> Result<Self> {
        if input.is_empty() {
            return Ok(Args { name: None });
        } else {
            Ok(Args {
                name: Some(input.parse()?),
            })
        }
    }
}

impl Fold for Args {
    fn fold_item_fn(&mut self, i: ItemFn) -> ItemFn {
        let block = fold::fold_block(self, *i.block);
        let ident = i.sig.ident.to_string();
        let name = self.name.clone().unwrap_or(parse_quote!(#ident));
        fold::fold_item_fn(self, ItemFn {
            block: Box::new(parse_quote!({
                use ark_std::{start_timer, end_timer};
                let _timer = start_timer!(|| #name);
                let result = #block;
                end_timer!(_timer);
                result
            })),
            ..i
        })
    }
}

#[proc_macro_attribute]
pub fn fn_timer(args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);

    let mut args = parse_macro_input!(args as Args);

    let output = args.fold_item_fn(input);

    TokenStream::from(quote!(#output))
}
