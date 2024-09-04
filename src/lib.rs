use groth16::{
    load_groth16_proof_from_bytes, load_groth16_verifying_key_from_bytes, verify_groth16,
};
use plonk::{load_plonk_proof_from_bytes, load_plonk_verifying_key_from_bytes, verify_plonk};

mod constants;
mod converter;
mod groth16;
mod hash_to_field;
mod plonk;
mod transcript;

pub trait Verifier {
    type Fr;

    fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Self::Fr]) -> bool;
}

pub struct Groth16Verifier;

impl Verifier for Groth16Verifier {
    type Fr = substrate_bn::Fr;

    fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Self::Fr]) -> bool {
        let proof = load_groth16_proof_from_bytes(proof).unwrap();
        let vk = load_groth16_verifying_key_from_bytes(vk).unwrap();

        match verify_groth16(&vk, &proof, public_inputs) {
            Ok(result) => result,
            Err(e) => {
                println!("Error: {:?}", e);
                false
            }
        }
    }
}

pub struct PlonkVerifier;

impl Verifier for PlonkVerifier {
    type Fr = substrate_bn::Fr;

    fn verify(proof: &[u8], vk: &[u8], public_inputs: &[Self::Fr]) -> bool {
        let proof = load_plonk_proof_from_bytes(proof).unwrap();
        let vk = load_plonk_verifying_key_from_bytes(vk).unwrap();

        match verify_plonk(&vk, &proof, public_inputs) {
            Ok(result) => result,
            Err(e) => {
                println!("Error: {:?}", e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tfms_tests {
    use ark_bn254::G2Affine;
    use ark_ec::AffineRepr;
    use ark_ff::BigInteger;
    use groth16::{
        convert_fr_sub_to_ark, convert_g1_ark_to_sub, convert_g1_sub_to_ark, convert_g2_ark_to_sub,
        convert_g2_sub_to_ark,
    };
    use substrate_bn::{AffineG1, AffineG2, Fq, Fq2, Fr};

    use super::*;

    #[test]
    fn test_substrate_to_ark() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        {
            for _ in 0..10 {
                let p = Fr::from_str(&rng.gen::<u64>().to_string()).unwrap();

                let mut p_bytes = [0u8; 32];
                p.to_big_endian(&mut p_bytes).unwrap();

                let ark_p = convert_fr_sub_to_ark(p);
                assert_eq!(p_bytes.to_vec(), ark_p.0.to_bytes_be());
            }
        }
        {
            for _ in 0..10 {
                // Generate a random x coordinate
                let x = Fq::random(&mut rng);

                // Compute y^2 = x^3 + b where b = 3
                let x_cubed = x * x * x;
                let y_squared = x_cubed + Fq::from_str("3").unwrap();

                // Compute y (if it exists)
                if let Some(y) = y_squared.sqrt() {
                    let p = AffineG1::new(x, y).expect("Failed to create AffineG1");
                    let ark_p = convert_g1_sub_to_ark(p);

                    // Verify that the conversion is correct
                    assert_eq!(p.x(), Fq::from_str(&ark_p.x.to_string()).unwrap());
                    assert_eq!(p.y(), Fq::from_str(&ark_p.y.to_string()).unwrap());

                    // Print x and y as bytes before conversion
                    let mut x_bytes = [0u8; 32];
                    let mut y_bytes = [0u8; 32];
                    p.x().to_big_endian(&mut x_bytes).unwrap();
                    p.y().to_big_endian(&mut y_bytes).unwrap();
                    println!("x bytes before: {:?}", x_bytes);
                    println!("y bytes before: {:?}", y_bytes);

                    assert_eq!(p, convert_g1_ark_to_sub(convert_g1_sub_to_ark(p)));
                }
            }
        }
    }
    // {
    //     for _ in 0..10 {
    //         // Generate a random x coordinate in Fq2
    //         let x = Fq2::new(Fq::random(&mut rng), Fq::random(&mut rng));

    //         // Compute y^2 = x^3 + b where b = Fq2::new(3, 3)
    //         let x_cubed = x * x * x;
    //         let b = Fq2::new(
    //             Fq::from_str(
    //                 "22799221013541087096367587346834441365989518998853065993049079013451698317998",
    //             )
    //             .unwrap(),
    //             Fq::from_str(
    //                 "403964309794472056394727851523360573920961648133464280908710223190906961620",
    //             )
    //             .unwrap(),
    //         );

    //         let y_squared = x_cubed + b;

    //         // Compute y (if it exists)
    //         if let Some(y) = y_squared.sqrt() {
    //             let p = AffineG2::new(x, y).expect("Failed to create AffineG2");
    //             let ark_p = convert_g2_sub_to_ark(p);

    //             // Verify that the conversion is correct
    //             assert_eq!(p.x().real(), Fq::from_str(&ark_p.x.c0.to_string()).unwrap());
    //             assert_eq!(
    //                 p.x().imaginary(),
    //                 Fq::from_str(&ark_p.x.c1.to_string()).unwrap()
    //             );
    //             assert_eq!(p.y().real(), Fq::from_str(&ark_p.y.c0.to_string()).unwrap());
    //             assert_eq!(
    //                 p.y().imaginary(),
    //                 Fq::from_str(&ark_p.y.c1.to_string()).unwrap()
    //             );
    //         }
    //     }
    // }

    #[test]
    fn test_affine_g2_one() {
        // Get the generator point (one) of G2
        let g2_one = AffineG2::one();

        let g2_one_bytes: [u8; 128] = unsafe { std::mem::transmute(g2_one) };
        println!("G2Affine::one() as bytes: {:?}", g2_one_bytes);

        // Extract x and y coordinates
        let x = g2_one.x();
        let y = g2_one.y();

        let x_bytes: [u8; 64] = unsafe { std::mem::transmute(x.0) };
        let y_bytes: [u8; 64] = unsafe { std::mem::transmute(y.0) };

        println!("G2 generator x: {:?}", x_bytes);
        println!("G2 generator y: {:?}", y_bytes);

        // Convert the G2 generator point to Arkworks representation
        let ark_g2_one = convert_g2_sub_to_ark(g2_one);

        // Print the coordinates for reference
        let mut x0_bytes = [0u8; 32];
        let mut x1_bytes = [0u8; 32];
        let mut y0_bytes = [0u8; 32];
        let mut y1_bytes = [0u8; 32];
        x.real().to_big_endian(&mut x0_bytes).unwrap();
        x.imaginary().to_big_endian(&mut x1_bytes).unwrap();
        y.real().to_big_endian(&mut y0_bytes).unwrap();
        y.imaginary().to_big_endian(&mut y1_bytes).unwrap();
        println!("G2 generator x0: {:?}", x0_bytes);
        println!("G2 generator x1: {:?}", x1_bytes);
        println!("G2 generator y0: {:?}", y0_bytes);
        println!("G2 generator y1: {:?}", y1_bytes);

        // Print the Arkworks representation
        let ark_g2_x0: [u8; 32] = unsafe { std::mem::transmute(ark_g2_one.x().unwrap().c0.0) };
        let ark_g2_x1: [u8; 32] = unsafe { std::mem::transmute(ark_g2_one.x().unwrap().c1.0) };
        let ark_g2_y0: [u8; 32] = unsafe { std::mem::transmute(ark_g2_one.y().unwrap().c0.0) };
        let ark_g2_y1: [u8; 32] = unsafe { std::mem::transmute(ark_g2_one.y().unwrap().c1.0) };
        println!("Arkworks G2 generator x0: {:?}", ark_g2_x0);
        println!("Arkworks G2 generator x1: {:?}", ark_g2_x1);
        println!("Arkworks G2 generator y0: {:?}", ark_g2_y0);
        println!("Arkworks G2 genrator y1: {:?}", ark_g2_y1);

        assert_eq!(g2_one, convert_g2_ark_to_sub(convert_g2_sub_to_ark(g2_one)));
    }
}
